"""Tests for per-client login page branding utilities."""

from nanoidp.branding import resolve_client_logo


class TestResolveClientLogo:
    """Test safe logo resolution."""

    def test_resolve_client_logo_finds_svg(self, tmp_path):
        """resolve_client_logo returns the filename when SVG exists."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        (logos_dir / "my-client.svg").touch()

        result = resolve_client_logo(str(logos_dir), "my-client")
        assert result == "my-client.svg"

    def test_resolve_client_logo_finds_png(self, tmp_path):
        """resolve_client_logo returns the filename when PNG exists."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        (logos_dir / "my-client.png").touch()

        result = resolve_client_logo(str(logos_dir), "my-client")
        assert result == "my-client.png"

    def test_resolve_client_logo_finds_jpeg(self, tmp_path):
        """resolve_client_logo returns the filename when JPEG exists."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        (logos_dir / "my-client.jpeg").touch()

        result = resolve_client_logo(str(logos_dir), "my-client")
        assert result == "my-client.jpeg"

    def test_resolve_client_logo_finds_jpg(self, tmp_path):
        """resolve_client_logo returns the filename when JPG exists."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        (logos_dir / "my-client.jpg").touch()

        result = resolve_client_logo(str(logos_dir), "my-client")
        assert result == "my-client.jpg"

    def test_resolve_client_logo_finds_webp(self, tmp_path):
        """resolve_client_logo returns the filename when WEBP exists."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        (logos_dir / "my-client.webp").touch()

        result = resolve_client_logo(str(logos_dir), "my-client")
        assert result == "my-client.webp"

    def test_resolve_client_logo_not_found(self, tmp_path):
        """resolve_client_logo returns None when no matching file exists."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()

        result = resolve_client_logo(str(logos_dir), "my-client")
        assert result is None

    def test_resolve_client_logo_prefers_first_extension(self, tmp_path):
        """resolve_client_logo returns the first matching extension found."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        (logos_dir / "my-client.svg").touch()
        (logos_dir / "my-client.png").touch()

        result = resolve_client_logo(str(logos_dir), "my-client")
        assert result == "my-client.svg"

    def test_resolve_client_logo_rejects_path_traversal_double_dot(self, tmp_path):
        """resolve_client_logo returns None for .. path traversal attempts."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        parent_dir = tmp_path / "parent.txt"
        parent_dir.touch()

        result = resolve_client_logo(str(logos_dir), "../parent")
        assert result is None

    def test_resolve_client_logo_rejects_path_traversal_slash(self, tmp_path):
        """resolve_client_logo returns None for / path traversal attempts."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()

        result = resolve_client_logo(str(logos_dir), "../../etc/passwd")
        assert result is None

    def test_resolve_client_logo_rejects_absolute_path(self, tmp_path):
        """resolve_client_logo returns None for absolute path attempts."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()

        result = resolve_client_logo(str(logos_dir), "/etc/passwd")
        assert result is None

    def test_resolve_client_logo_allows_underscores_and_hyphens(self, tmp_path):
        """resolve_client_logo allows client IDs with underscores and hyphens."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        (logos_dir / "my_client-app.png").touch()

        result = resolve_client_logo(str(logos_dir), "my_client-app")
        assert result == "my_client-app.png"

    def test_resolve_client_logo_rejects_special_chars(self, tmp_path):
        """resolve_client_logo rejects client IDs with special characters."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()

        result = resolve_client_logo(str(logos_dir), "my-client;rm -rf/")
        assert result is None

    def test_resolve_client_logo_rejects_spaces(self, tmp_path):
        """resolve_client_logo rejects client IDs with spaces."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()

        result = resolve_client_logo(str(logos_dir), "my client")
        assert result is None

    def test_resolve_client_logo_with_relative_path(self, tmp_path, monkeypatch):
        """resolve_client_logo works with relative paths."""
        logos_dir = tmp_path / "logos"
        logos_dir.mkdir()
        (logos_dir / "my-client.png").touch()

        monkeypatch.chdir(str(tmp_path.parent))
        result = resolve_client_logo(str(logos_dir.relative_to(tmp_path.parent)), "my-client")
        assert result == "my-client.png"
