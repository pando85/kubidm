import sys
from pathlib import Path

import mkdocs_gen_files


def files_match(file1: Path, file2: Path) -> bool:
    """Check if two files have identical content."""
    if not file1.exists() or not file2.exists():
        return False
    return file1.read_bytes() == file2.read_bytes()


def main() -> None:

    pykubidm_dir = Path(__file__).parent.parent.parent
    docs_dir = pykubidm_dir / "docs"
    readme_src = pykubidm_dir / "README.md"
    target_index = Path("index.md")
    if not readme_src.exists():
        raise FileNotFoundError(readme_src)

    readme_text = readme_src.read_text(encoding="utf-8")
    with mkdocs_gen_files.open(target_index, "w", encoding="utf-8") as fp:
        fp.write(readme_text.replace("artwork/brand/horizontal.svg", "assets/kubidm-horizontal.svg"))
        print(f"Generated README.md for documentation at {docs_dir / target_index}", file=sys.stderr)

    mkdocs_gen_files.set_edit_path(target_index, readme_src)

    # The docs index is generated from the root README. Rewrite its image URL
    # because MkDocs renders it from a different base directory.
    asset_source = pykubidm_dir.parent / "artwork/brand/horizontal.svg"
    asset_target = Path("assets/kubidm-horizontal.svg")
    if not asset_source.exists():
        raise FileNotFoundError(asset_source)
    with mkdocs_gen_files.open(asset_target, "w", encoding="utf-8") as fp:
        fp.write(asset_source.read_text(encoding="utf-8"))
    mkdocs_gen_files.set_edit_path(asset_target, asset_source)
