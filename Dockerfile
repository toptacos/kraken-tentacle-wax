FROM python:3.12-alpine
WORKDIR /opt/wax
COPY . .
CMD ["python3", "tests/test_cask.py", "-v"]
