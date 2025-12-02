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

echo "Processing 'files' and 'selfextracted' folders under $BASE_DIR..."

# Loop through each analysis subdirectory
find "$BASE_DIR" -mindepth 1 -maxdepth 1 -type d | while read -r ANALYSIS_DIR; do
    # Handle 'files'
    if [ -d "$ANALYSIS_DIR/files" ]; then
        if [ "$DRY_RUN" = true ]; then
            find "$ANALYSIS_DIR/files" -mindepth 1 -print
        else
            rm -rfv "$ANALYSIS_DIR/files/"*
            echo "Cleared $ANALYSIS_DIR/files"
        fi
    fi

    # Handle 'selfextracted'
    if [ -d "$ANALYSIS_DIR/selfextracted" ]; then
        if [ "$DRY_RUN" = true ]; then
            find "$ANALYSIS_DIR/selfextracted" -mindepth 1 -print
        else
            rm -rfv "$ANALYSIS_DIR/selfextracted/"*
            echo "Cleared $ANALYSIS_DIR/selfextracted"
        fi
    fi
done

echo "Done."
