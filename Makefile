.PHONY: test

# Define the default target
test:
    @echo "Running all tests in the project..."
    go test ./...

# Target to run tests in the utils directory
.PHONY: test_utils
test_utils:
    @echo "Running tests in the utils directory..."
    go test ./utils/...