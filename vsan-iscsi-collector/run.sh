#!/bin/zsh
############################################################################################################
# THIS IS EXAMPLE CODE! USE AT YOUR OWN RISK. DO NOT USE IN PRODUCTION ENVIRONMENTS WITHOUT PROPER TESTING AND REVIEW
############################################################################################################

# Get the directory where this script is located
SCRIPT_DIR="${0:A:h}"
cd "$SCRIPT_DIR"

VENV_DIR="venv"
PYTHON_SCRIPT="vsan-iscsi-collector.py"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# echo "${GREEN}vSAN iSCSI Collector - Startup Script${NC}"

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo "${YELLOW}Virtual environment not found. Creating...${NC}"
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create virtual environment"
        exit 1
    fi
fi

# Activate virtual environment
#echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Install/upgrade requirements
if [ -f "requirements.txt" ]; then
    #echo "Installing/updating dependencies..."
    pip install -q -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "Error: Failed to install requirements"
        exit 1
    fi
fi

# Run the Python script with all passed arguments
#echo "${GREEN}Starting vSAN iSCSI Collector...${NC}"
python3 "$PYTHON_SCRIPT" "$@"

# Capture exit code
EXIT_CODE=$?

# Deactivate virtual environment
deactivate

exit $EXIT_CODE

