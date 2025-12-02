#!/bin/bash
# Renames files in a folder to their SHA-256 hash with .exe extension

usage() {
    echo "Usage: $0 <folder_path>"
    echo ""
    echo "This script renames all files in the specified folder to their SHA-256 hash with .exe extension"
    echo "Example: $0 /path/to/folder"
    exit 1
}

# Check if folder path is provided
if [ $# -ne 1 ]; then
    usage
fi

FOLDER="$1"

# Check if folder exists
if [ ! -d "$FOLDER" ]; then
    echo "Error: '$FOLDER' is not a valid directory"
    exit 1
fi

echo "Renaming files in: $FOLDER"

# Count files
file_count=$(find "$FOLDER" -maxdepth 1 -type f | wc -l)
echo "Found $file_count files to process"

# Confirm before proceeding
read -p "This will rename ALL files in the folder. Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    exit 0
fi

renamed_count=0
failed_count=0

# Process each file in the folder
find "$FOLDER" -maxdepth 1 -type f -print0 | while IFS= read -r -d '' file; do
    filename=$(basename "$file")
    echo "Processing: $filename"
    
    # Calculate SHA-256 hash
    if hash_value=$(sha256sum "$file" 2>/dev/null); then
        # Extract just the hash (first field)
        hash_only=$(echo "$hash_value" | cut -d' ' -f1)
        new_name="${hash_only}.exe"
        new_path="${FOLDER}/${new_name}"
        
        # Check if target already exists and is different file
        if [ -f "$new_path" ] && [ "$file" != "$new_path" ]; then
            echo "  Warning: Target filename already exists: $new_name"
            echo "  Skipping $filename"
            ((failed_count++))
            continue
        fi
        
        # Skip if file already has correct name
        if [ "$filename" = "$new_name" ]; then
            echo "  Already has correct name: $new_name"
            continue
        fi
        
        # Rename the file
        if mv "$file" "$new_path" 2>/dev/null; then
            echo "  Renamed: $filename → $new_name"
            ((renamed_count++))
        else
            echo "  Failed to rename $filename"
            ((failed_count++))
        fi
    else
        echo "  Error calculating hash for $filename"
        ((failed_count++))
    fi
done

echo ""
echo "Done. Renamed $renamed_count file(s), $failed_count failed."
