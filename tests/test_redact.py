from docksec.redact import redact_content, REDACTED


def test_redacts_dockerfile_env_equals():
    content = 'FROM python:3.12\nENV DB_PASSWORD=hunter2\nENV APP_NAME=myapp\n'
    redacted, count = redact_content(content)
    assert count == 1
    assert 'hunter2' not in redacted
    assert f'DB_PASSWORD={REDACTED}' in redacted
    assert 'APP_NAME=myapp' in redacted


def test_redacts_dockerfile_env_space_form():
    content = 'ENV API_KEY abc123secretvalue\n'
    redacted, count = redact_content(content)
    assert count == 1
    assert 'abc123secretvalue' not in redacted
    assert 'API_KEY' in redacted


def test_redacts_arg_and_multiple_pairs():
    content = 'ARG GITHUB_TOKEN=ghx123\nENV A=1 SECRET_KEY=s3cr3t B=2\n'
    redacted, count = redact_content(content)
    assert count == 2
    assert 'ghx123' not in redacted
    assert 's3cr3t' not in redacted
    assert 'A=1' in redacted and 'B=2' in redacted


def test_redacts_compose_environment_styles():
    content = (
        'services:\n'
        '  db:\n'
        '    environment:\n'
        '      - MYSQL_ROOT_PASSWORD=secret\n'
        '      POSTGRES_PASSWORD: alsosecret\n'
    )
    redacted, count = redact_content(content)
    assert count == 2
    assert 'secret' not in redacted.replace(REDACTED, '')


def test_leaves_interpolations_alone():
    content = 'ENV DB_PASSWORD=${DB_PASSWORD}\n'
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content


def test_redacts_value_shaped_secrets_regardless_of_key():
    content = 'RUN aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE\n'
    redacted, count = redact_content(content)
    assert count >= 1
    assert 'AKIAIOSFODNN7EXAMPLE' not in redacted


def test_redacts_private_key_block():
    content = (
        'COPY key.pem /app\n'
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'MIIEpAIBAAKCAQEA\n'
        '-----END RSA PRIVATE KEY-----\n'
    )
    redacted, count = redact_content(content)
    assert count == 1
    assert 'MIIEpAIBAAKCAQEA' not in redacted


def test_no_secrets_no_change():
    content = 'FROM alpine:3.19\nRUN apk add --no-cache curl\nUSER nobody\n'
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content
