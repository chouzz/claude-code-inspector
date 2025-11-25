"""Basic tests for Claude-Code-Inspector."""

import pytest

from cci import __version__
from cci.config import CCIConfig, FilterConfig, load_config
from cci.filters import URLFilter
from cci.models import RecordType, RequestRecord
from cci.storage import JSONLWriter


class TestVersion:
    """Test version information."""

    def test_version_exists(self) -> None:
        """Test that version is defined."""
        assert __version__ is not None
        assert isinstance(__version__, str)

    def test_version_format(self) -> None:
        """Test that version follows semver format."""
        parts = __version__.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


class TestConfig:
    """Test configuration module."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = CCIConfig()
        assert config.proxy.host == "127.0.0.1"
        assert config.proxy.port == 8080
        assert config.masking.mask_auth_headers is True

    def test_filter_config_defaults(self) -> None:
        """Test default filter patterns include major LLM providers."""
        config = FilterConfig()
        patterns = config.include_patterns
        assert any("anthropic" in p for p in patterns)
        assert any("openai" in p for p in patterns)
        assert any("googleapis" in p for p in patterns)


class TestURLFilter:
    """Test URL filtering."""

    def test_anthropic_url_matches(self) -> None:
        """Test that Anthropic API URLs are matched."""
        config = FilterConfig()
        url_filter = URLFilter(config)
        assert url_filter.should_capture("https://api.anthropic.com/v1/messages")

    def test_openai_url_matches(self) -> None:
        """Test that OpenAI API URLs are matched."""
        config = FilterConfig()
        url_filter = URLFilter(config)
        assert url_filter.should_capture("https://api.openai.com/v1/chat/completions")

    def test_random_url_not_matched(self) -> None:
        """Test that random URLs are not matched."""
        config = FilterConfig()
        url_filter = URLFilter(config)
        assert not url_filter.should_capture("https://example.com/api")

    def test_exclude_pattern(self) -> None:
        """Test that exclude patterns work."""
        config = FilterConfig(
            include_patterns=[".*example\\.com.*"],
            exclude_patterns=[".*health.*"],
        )
        url_filter = URLFilter(config)
        assert url_filter.should_capture("https://example.com/api")
        assert not url_filter.should_capture("https://example.com/health")


class TestModels:
    """Test data models."""

    def test_request_record_creation(self) -> None:
        """Test creating a request record."""
        record = RequestRecord(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
        )
        assert record.type == RecordType.REQUEST
        assert record.method == "POST"
        assert record.id is not None

    def test_request_record_with_body(self) -> None:
        """Test request record with body."""
        body = {"model": "claude-3-sonnet", "messages": []}
        record = RequestRecord(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            body=body,
        )
        assert record.body == body


class TestStorage:
    """Test storage module."""

    def test_jsonl_writer_creation(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test creating a JSONL writer."""
        output_file = tmp_path / "test.jsonl"  # type: ignore
        writer = JSONLWriter(output_file)
        assert writer.output_path == output_file

    def test_jsonl_writer_write(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test writing records to JSONL."""
        output_file = tmp_path / "test.jsonl"  # type: ignore
        with JSONLWriter(output_file) as writer:
            record = RequestRecord(
                method="POST",
                url="https://api.anthropic.com/v1/messages",
            )
            writer.write_record(record)

        # Read and verify
        with open(output_file) as f:
            content = f.read()
        assert "request" in content
        assert "anthropic" in content

