"""Application web `vigie-web` (SPEC §9, SECURITY.md C9).

Le processus web ne détient que ses propres secrets (clé de session, secret client Entra) :
ni secret de source, ni clé Anthropic, et il n'importe ni connecteur ni client LLM
(règle 5 de CLAUDE.md, vérifiée par test). Les actions vers les sources passent par
`job_request`, exécutées par le worker.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from vigie.config import VigieConfig
from vigie.db import models
from vigie.db.enums import AppRole
from vigie.db.session import make_engine
from vigie.web.auth import (
    AccessDeniedError,
    LoginRequiredError,
    OIDCClient,
    User,
    audit,
    breakglass_active,
    check_breakglass,
    current_user,
    dev_login_enabled,
    open_session,
    user_from_claims,
)
from vigie.web.deps import DB, render
from vigie.web.security import SecurityHeaders, csrf_protect

STATIC_DIR = Path(__file__).parent / "static"
SESSION_COOKIE = "vigie_session"


def landing_path(user: User) -> str:
    return "/semaine" if user.role is AppRole.viewer else "/aujourdhui"


def create_app(
    cfg: VigieConfig,
    *,
    session_key: str,
    oidc_client: OIDCClient | None = None,
    engine: Engine | Connection | None = None,
    env: Mapping[str, str] | None = None,
) -> FastAPI:
    env = os.environ if env is None else env
    dev = env.get("VIGIE_ENV") == "dev"
    max_age = cfg.web.session_hours * 3600
    dev_login = dev_login_enabled(cfg.web.dev_login, cfg.web.host, env)

    async def attach_user(request: Request) -> None:
        request.state.user = current_user(request, max_age)

    app = FastAPI(
        title="Vigie",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        dependencies=[Depends(attach_user), Depends(csrf_protect)],
    )
    app.state.cfg = cfg
    bind = engine if engine is not None else make_engine(cfg.web.database_url or cfg.database.url)
    app.state.engine = bind
    # Connexion fournie (tests) : chaque validation devient un point de sauvegarde.
    app.state.sessionmaker = sessionmaker(
        bind=bind, expire_on_commit=False, join_transaction_mode="create_savepoint"
    )
    app.state.oidc = oidc_client
    app.state.dev_login = dev_login

    app.add_middleware(
        SessionMiddleware,
        secret_key=session_key,
        session_cookie=SESSION_COOKIE,
        max_age=max_age,
        same_site="lax",
        https_only=not dev,
    )
    app.add_middleware(SecurityHeaders, hsts=not dev)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.exception_handler(LoginRequiredError)
    async def _login_required(request: Request, exc: LoginRequiredError) -> Response:
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Authentification requise."}, status_code=401)
        if request.headers.get("hx-request"):
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException) -> Response:
        if request.url.path.startswith("/api/") or request.headers.get("hx-request"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return render(
            request,
            "error.html",
            {"status": exc.status_code, "detail": exc.detail},
            exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError) -> Response:
        # Pas de reprise des valeurs reçues dans la réponse.
        fields = sorted({".".join(str(p) for p in e["loc"][1:]) for e in exc.errors()})
        detail = "Données invalides : " + ", ".join(fields)
        if request.url.path.startswith("/api/") or request.headers.get("hx-request"):
            return JSONResponse({"detail": detail}, status_code=422)
        return render(request, "error.html", {"status": 422, "detail": detail}, 422)

    # --- Santé et entrée ----------------------------------------------------------------

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/", include_in_schema=False)
    def home(request: Request) -> Response:
        user: User | None = request.state.user
        return RedirectResponse(landing_path(user) if user else "/login", status_code=303)

    # --- Connexion ----------------------------------------------------------------------

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, session: DB) -> Response:
        if request.state.user is not None:
            return RedirectResponse(landing_path(request.state.user), status_code=303)
        return render(
            request,
            "login.html",
            {
                "entra": app.state.oidc is not None,
                "dev_login": app.state.dev_login,
                "breakglass": breakglass_active(session, datetime.now(UTC)),
                "error": request.session.pop("login_error", None),
            },
        )

    @app.get("/auth/login")
    async def entra_login(request: Request) -> Response:
        if app.state.oidc is None:
            raise HTTPException(status_code=404)
        redirect_uri = str(request.url_for("entra_callback"))
        result: Response = await app.state.oidc.authorize_redirect(request, redirect_uri)
        return result

    @app.get("/auth/callback", name="entra_callback")
    async def entra_callback(request: Request, session: DB) -> Response:
        if app.state.oidc is None:
            raise HTTPException(status_code=404)
        try:
            token = await app.state.oidc.authorize_access_token(request)
        except Exception:  # réponse d'Entra invalide, état ou nonce faux : refus
            audit(session, "anonyme", "login_failed", "entra", reason="échange du code refusé")
            session.commit()
            request.session["login_error"] = "La connexion Entra a échoué. Réessayez."
            return RedirectResponse("/login", status_code=303)
        claims: dict[str, Any] = dict(token.get("userinfo") or {})
        try:
            user = user_from_claims(session, claims, cfg.web.oidc)
        except AccessDeniedError as exc:
            who = str(claims.get("preferred_username") or claims.get("email") or "inconnu")
            audit(session, who, "login_denied", "entra", reason=exc.reason)
            session.commit()
            raise HTTPException(status_code=403, detail=f"Accès refusé : {exc.reason}.") from None
        open_session(request, user)
        audit(session, user.email, "login", "entra", role=user.role.value)
        session.commit()
        return RedirectResponse(landing_path(user), status_code=303)

    @app.get("/dev-login", response_class=HTMLResponse)
    def dev_login_page(request: Request, session: DB) -> Response:
        if not app.state.dev_login:
            raise HTTPException(status_code=404)
        people = session.scalars(
            select(models.Person).where(models.Person.active.is_(True)).order_by(models.Person.name)
        ).all()
        return render(request, "dev_login.html", {"people": people, "roles": list(AppRole)})

    @app.post("/dev-login")
    def dev_login_submit(
        request: Request,
        person_id: Annotated[int, Form()],
        role: Annotated[AppRole, Form()],
        session: DB,
    ) -> Response:
        if not app.state.dev_login:
            raise HTTPException(status_code=404)
        person = session.get(models.Person, person_id)
        if person is None or not person.active:
            raise HTTPException(status_code=422, detail="Personne inconnue.")
        user = User(person.name, person.email, role, person.id, "dev")
        open_session(request, user)
        audit(session, user.email, "login", "dev", role=role.value)
        session.commit()
        return RedirectResponse(landing_path(user), status_code=303)

    @app.get("/breakglass", response_class=HTMLResponse)
    def breakglass_page(request: Request, session: DB) -> Response:
        if not breakglass_active(session, datetime.now(UTC)):
            raise HTTPException(status_code=404)
        return render(request, "breakglass.html")

    @app.post("/breakglass")
    def breakglass_submit(
        request: Request, password: Annotated[str, Form(max_length=200)], session: DB
    ) -> Response:
        now = datetime.now(UTC)
        if not breakglass_active(session, now):
            raise HTTPException(status_code=404)
        if not check_breakglass(session, password, now):
            audit(session, "bris de glace", "login_failed", "breakglass")
            session.commit()
            raise HTTPException(status_code=403, detail="Mot de passe de secours invalide.")
        user = User("Bris de glace", "breakglass@vigie.local", AppRole.admin, None, "breakglass")
        open_session(request, user)
        audit(session, user.email, "login", "breakglass", role="admin")
        session.commit()
        return RedirectResponse("/aujourdhui", status_code=303)

    @app.post("/logout")
    def logout(request: Request, session: DB) -> Response:
        user: User | None = request.state.user
        if user is not None:
            audit(session, user.email, "logout", user.via)
            session.commit()
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    from vigie.web.routes import register

    register(app)
    return app


def build_from_env() -> FastAPI:
    """Fabrique pour uvicorn (`vigie web`) : configuration et secrets du processus web
    seulement (clé de session, secret client Entra)."""
    from vigie.config import get_secret, load_config, resolve_config_path
    from vigie.web.auth import make_entra_client

    cfg = load_config(resolve_config_path())
    session_key = get_secret("web_session_key").get_secret_value()
    oidc = None
    if cfg.web.oidc.configured:
        secret = get_secret("entra_client_secret").get_secret_value()
        oidc = make_entra_client(cfg.web.oidc, secret)
    return create_app(cfg, session_key=session_key, oidc_client=oidc)
