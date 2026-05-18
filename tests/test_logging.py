"""Tests for centralized logging configuration."""

import ast
import logging
import os

import pytest


@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging state between tests to avoid handler pollution.
    
    logging.basicConfig() is a no-op when the root logger already has handlers,
    so we must clear handlers AND reset the root logger's level before each test.
    We also set force=True-compatible state by removing the root's handler list.
    """
    # Setup: ensure clean state before each test
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.WARNING)
    # Reset the internal flag that basicConfig uses to skip re-configuration
    # by removing all handlers (already done above). On Python 3.8+,
    # basicConfig checks len(root.handlers) == 0 before configuring.
    yield
    # Teardown: clean up after each test
    root = logging.getLogger()
    for handler in root.handlers[:]:
        handler.close()
        root.removeHandler(handler)
    root.setLevel(logging.WARNING)


class TestConfigureLogging:
    """Tests for the configure_logging() function."""

    def test_configure_logging_default_level(self):
        """Test 1: Default call sets root logger to WARNING."""
        from docksec.utils import configure_logging

        configure_logging()
        root = logging.getLogger()
        assert root.level == logging.WARNING

    def test_configure_logging_verbose_level(self):
        """Test 2: verbose=True sets root logger to INFO."""
        from docksec.utils import configure_logging

        configure_logging(verbose=True)
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_configure_logging_debug_level(self):
        """Test 3: debug=True sets root logger to DEBUG."""
        from docksec.utils import configure_logging

        configure_logging(debug=True)
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_configure_logging_debug_implies_verbose(self):
        """Test 4: debug=True should produce the most permissive level (DEBUG)."""
        from docksec.utils import configure_logging

        configure_logging(debug=True)
        root = logging.getLogger()
        # DEBUG (10) is more permissive than INFO (20) and WARNING (30)
        assert root.level == logging.DEBUG
        assert root.level < logging.INFO

    def test_configure_logging_file_handler(self, tmp_path):
        """Test 5: log_file parameter creates a file handler and writes to disk."""
        from docksec.utils import configure_logging

        log_file = tmp_path / "test.log"
        configure_logging(verbose=True, log_file=str(log_file))

        # Log a message so the file gets written to
        test_logger = logging.getLogger("test_file_handler")
        test_logger.info("Test log message")

        assert log_file.exists()
        content = log_file.read_text()
        assert "Test log message" in content

    def test_no_print_calls_in_library_code(self):
        """Test 6: Verify zero print() calls remain in library code.

        Uses AST parsing to scan docker_scanner.py (excluding the main()
        entrypoint), score_calculator.py, and report_generator.py.
        """
        base_dir = os.path.join(os.path.dirname(__file__), "..", "docksec")
        files_to_check = [
            "score_calculator.py",
            "report_generator.py",
        ]

        violations = []

        for filename in files_to_check:
            filepath = os.path.join(base_dir, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=filepath)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name) and func.id == "print":
                        violations.append(
                            f"{filename}:{node.lineno} - print() call found"
                        )

        # For docker_scanner.py, exclude the top-level main() function.
        # ast.walk visits ALL descendants, so we need to manually skip
        # the body of the main() function.
        docker_scanner_path = os.path.join(base_dir, "docker_scanner.py")
        with open(docker_scanner_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=docker_scanner_path)

        # Collect line ranges for the top-level main() function to exclude
        main_func_lines = set()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "main":
                # Mark all lines in main() as excluded
                for child in ast.walk(node):
                    if hasattr(child, "lineno"):
                        main_func_lines.add(child.lineno)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "print":
                    if node.lineno not in main_func_lines:
                        violations.append(
                            f"docker_scanner.py:{node.lineno} - print() call found"
                        )

        assert violations == [], (
            f"Found {len(violations)} print() call(s) in library code:\n"
            + "\n".join(violations)
        )
