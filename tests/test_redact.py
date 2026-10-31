from docksec.redact import REDACTED, redact_content


def test_redacts_dockerfile_env_equals():
    content = "FROM python:3.12\nENV DB_PASSWORD=hunter2\nENV APP_NAME=myapp\n"
    redacted, count = redact_content(content)
    assert count == 1
    assert "hunter2" not in redacted
    assert f"DB_PASSWORD={REDACTED}" in redacted
    assert "APP_NAME=myapp" in redacted


def test_redacts_dockerfile_env_space_form():
    content = "ENV API_KEY abc123secretvalue\n"
    redacted, count = redact_content(content)
    assert count == 1
    assert "abc123secretvalue" not in redacted
    assert "API_KEY" in redacted


def test_redacts_arg_and_multiple_pairs():
    content = "ARG GITHUB_TOKEN=ghx123\nENV A=1 SECRET_KEY=s3cr3t B=2\n"
    redacted, count = redact_content(content)
    assert count == 2
    assert "ghx123" not in redacted
    assert "s3cr3t" not in redacted
    assert "A=1" in redacted and "B=2" in redacted


def test_redacts_compose_environment_styles():
    content = (
        "services:\n"
        "  db:\n"
        "    environment:\n"
        "      - MYSQL_ROOT_PASSWORD=secret\n"
        "      POSTGRES_PASSWORD: alsosecret\n"
    )
    redacted, count = redact_content(content)
    assert count == 2
    assert "secret" not in redacted.replace(REDACTED, "")


def test_leaves_interpolations_alone():
    content = "ENV DB_PASSWORD=${DB_PASSWORD}\n"
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content


def test_redacts_value_shaped_secrets_regardless_of_key():
    content = "RUN aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE\n"
    redacted, count = redact_content(content)
    assert count >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted


def test_redacts_private_key_block():
    content = (
        "COPY key.pem /app\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    redacted, count = redact_content(content)
    assert count == 1
    assert "MIIEpAIBAAKCAQEA" not in redacted


def test_redacts_password_in_url_credentials():
    content = (
        "ENV DATABASE_URL=postgres://admin:s3cr3tPass@db:5432/app\n"
        "ENV REDIS_URL=redis://:mypassword@cache:6379/0\n"
        '      - "AMQP_URL=amqp://user:rabbitpw@broker:5672/"\n'
        "ENV MONGO_URI mongodb://root:supersecret@mongo:27017\n"
    )
    redacted, count = redact_content(content)
    assert count == 4
    for secret in ("s3cr3tPass", "mypassword", "rabbitpw", "supersecret"):
        assert secret not in redacted
    # Scheme, user, and host stay visible so the model can still flag it.
    assert f"postgres://admin:{REDACTED}@db:5432/app" in redacted
    assert f"redis://:{REDACTED}@cache:6379/0" in redacted


def test_leaves_url_without_password_alone():
    content = (
        "ENV APP_URL=https://example.com/health\n" "ENV HOST=postgres://db:5432/app\n"
    )
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content


def test_no_secrets_no_change():
    content = "FROM alpine:3.19\nRUN apk add --no-cache curl\nUSER nobody\n"
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content


def test_redacts_compose_default_value():
    content = "ENV DB_PASSWORD=${DB_PASSWORD:-fallback111}\n"
    redacted, count = redact_content(content)
    assert count == 1
    assert "fallback111" not in redacted


def test_redacts_mixed_interpolation_and_literal():
    content = "ENV DB_PASSWORD=${DB_PASSWORD}suffix111\nENV OTHER_TOKEN=pre222${OTHER_TOKEN}\n"
    redacted, count = redact_content(content)
    assert count == 2
    assert "suffix111" not in redacted
    assert "pre222" not in redacted


def test_leaves_quoted_placeholder_alone():
    content = 'ENV DB_PASSWORD="${DB_PASSWORD}"\n'
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content


def test_redacts_command_substitution():
    content = "ENV DB_PASSWORD=$(cat /run/secrets/db)\n"
    redacted, count = redact_content(content)
    assert count == 1
    assert "cat /run/secrets/db" not in redacted
