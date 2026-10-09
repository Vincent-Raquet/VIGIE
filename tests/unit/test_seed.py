"""Lecture et validation des données d'amorçage (sans base)."""

import shutil
from pathlib import Path

import pytest
import yaml

from tests.conftest import REPO_ROOT
from vigie.seed import SeedError, load_seed_data, parse_role_skill, pick_file

CONFIG = REPO_ROOT / "config"
ROLES = REPO_ROOT / "roles"


@pytest.fixture
def seed_dir(tmp_path: Path) -> Path:
    d = tmp_path / "config"
    d.mkdir()
    for stem in ("team", "companies", "policy"):
        shutil.copy(CONFIG / f"{stem}.example.yaml", d / f"{stem}.example.yaml")
    return d


def _edit(path: Path, mutate: object) -> None:
    data = yaml.safe_load(path.read_text())
    mutate(data)  # type: ignore[operator]
    path.write_text(yaml.safe_dump(data, allow_unicode=True))


def test_example_files_load() -> None:
    data = load_seed_data(CONFIG, ROLES)
    assert [p.name for p in data.team.people] == ["Vincent", "Giovanni", "Cédric", "Angelo"]
    assert {s.name for s in data.role_skills} == {
        "ingenieur-coordinateur",
        "responsable-informatique",
    }
    assert data.example_files == [
        "team.example.yaml",
        "companies.example.yaml",
        "policy.example.yaml",
        "scoring.example.yaml",
    ]
    assert data.scoring is not None


def test_real_file_preferred_over_example(seed_dir: Path) -> None:
    shutil.copy(seed_dir / "team.example.yaml", seed_dir / "team.yaml")
    path, is_example = pick_file(seed_dir, "team")
    assert path.name == "team.yaml"
    assert not is_example
    assert "team.example.yaml" not in load_seed_data(seed_dir, ROLES).example_files


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SeedError, match="introuvable"):
        pick_file(tmp_path, "team")


def test_invalid_yaml(seed_dir: Path) -> None:
    (seed_dir / "team.example.yaml").write_text("people: [\n")
    with pytest.raises(SeedError, match="YAML invalide"):
        load_seed_data(seed_dir, ROLES)


def test_yaml_must_be_mapping(seed_dir: Path) -> None:
    (seed_dir / "team.example.yaml").write_text("- a\n")
    with pytest.raises(SeedError, match="dictionnaire"):
        load_seed_data(seed_dir, ROLES)


def test_yaml_tags_are_not_executed(seed_dir: Path) -> None:
    (seed_dir / "team.example.yaml").write_text("people: !!python/object/apply:os.getcwd []\n")
    with pytest.raises(SeedError, match="YAML invalide"):
        load_seed_data(seed_dir, ROLES)


def test_skill_level_out_of_range(seed_dir: Path) -> None:
    _edit(seed_dir / "team.example.yaml", lambda d: d["people"][0]["skills"].update(reseau=4))
    with pytest.raises(SeedError, match=r"team\.example\.yaml invalide"):
        load_seed_data(seed_dir, ROLES)


def test_unknown_field_rejected(seed_dir: Path) -> None:
    _edit(seed_dir / "team.example.yaml", lambda d: d["people"][0].update(salary=1))
    with pytest.raises(SeedError, match="salary"):
        load_seed_data(seed_dir, ROLES)


def test_cross_references_all_reported(seed_dir: Path) -> None:
    def mutate_policy(d: dict) -> None:  # type: ignore[type-arg]
        d["projects"][0]["owner"] = "Inconnu"
        d["projects"][0]["companies"].append("XX")
        d["projects"][0]["axes"].append("Axe fantôme")
        d["projects"][0]["milestones"][0]["depends_on"] = ["Jalon fantôme"]

    _edit(seed_dir / "policy.example.yaml", mutate_policy)
    _edit(
        seed_dir / "companies.example.yaml",
        lambda d: d["asset_rules"].append(
            {"source": "zabbix", "match": "hostgroup_prefix", "pattern": "ZZ", "company": "ZZ"}
        ),
    )
    _edit(seed_dir / "team.example.yaml", lambda d: d["people"][0].update(role_skill="absent"))
    with pytest.raises(SeedError) as excinfo:
        load_seed_data(seed_dir, ROLES)
    message = str(excinfo.value)
    for expected in (
        "responsable inconnu 'Inconnu'",
        "société inconnue 'XX'",
        "axe inconnu 'Axe fantôme'",
        "dépendance invalide 'Jalon fantôme'",
        "société inconnue 'ZZ'",
        "skill de rôle inconnu 'absent'",
    ):
        assert expected in message


def test_duplicates_rejected(seed_dir: Path) -> None:
    _edit(
        seed_dir / "team.example.yaml",
        lambda d: d["people"].append(dict(d["people"][1], email="autre@example.be")),
    )
    with pytest.raises(SeedError, match="personne en double : Giovanni"):
        load_seed_data(seed_dir, ROLES)


def test_asset_rule_without_effect_rejected(seed_dir: Path) -> None:
    _edit(
        seed_dir / "companies.example.yaml",
        lambda d: d["asset_rules"].append(
            {"source": "zabbix", "match": "hostgroup_prefix", "pattern": "X"}
        ),
    )
    with pytest.raises(SeedError, match="société ou une criticité"):
        load_seed_data(seed_dir, ROLES)


def _skill(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name / "SKILL.md"
    path.parent.mkdir()
    path.write_text(content)
    return path


def test_role_skill_frontmatter(tmp_path: Path) -> None:
    path = _skill(tmp_path, "demo", "---\nname: demo\ndescription: Démo\n---\n\n# Corps\n")
    skill = parse_role_skill(path)
    assert skill.name == "demo"
    assert skill.body_md == "# Corps\n"


@pytest.mark.parametrize(
    ("content", "match"),
    [
        ("# pas de frontmatter\n", "frontmatter YAML"),
        ("---\n[\n---\ncorps\n", "frontmatter invalide"),
        ("---\n- a\n---\ncorps\n", "frontmatter invalide"),
        ("---\nname: autre\ndescription: x\n---\ncorps\n", "différent du dossier"),
        ("---\nname: Demo!\ndescription: x\n---\ncorps\n", "SKILL.md"),
    ],
)
def test_role_skill_errors(tmp_path: Path, content: str, match: str) -> None:
    with pytest.raises(SeedError, match=match):
        parse_role_skill(_skill(tmp_path, "demo", content))
