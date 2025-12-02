#!/bin/bash

# Set base directory
BASE_DIR="/opt/CAPEv2/storage/analyses"

# Check for dry-run mode
DRY_RUN=false
if [ "$1" == "--dry-run" ]; then
    DRY_RUN=true
    echo "Running in DRY-RUN mode (no files will be deleted)."
fi

# Confirm directory exists
if [ ! -d "$BASE_DIR" ]; then
    echo "Error: Directory $BASE_DIR does not exist."
    exit 1
fi

echo "Processing 'reports' folders under $BASE_DIR..."

# Loop through each analysis subdirectory
find "$BASE_DIR" -mindepth 1 -maxdepth 1 -type d | while read -r ANALYSIS_DIR; do
    if [ -d "$ANALYSIS_DIR/reports" ]; then
        if [ "$DRY_RUN" = true ]; then
            echo "Would remove: $ANALYSIS_DIR/reports"
        else
            rm -rfv "$ANALYSIS_DIR/reports"
            echo "Removed $ANALYSIS_DIR/reports"
        fi
    fi
done

echo "Done."
