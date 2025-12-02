# Helper-Scripts

These scripts were used during Thesis 3 to help the researchers in building their malware dataset. All of the files found within this repository are used to simply streamline the pipeline process of malware analysis within the VM.

remove_reports.sh: Free up space by removing the reports within each folder inside CAPE directory

clear_name.sh: Changes the name of a file to its SHA256 hash and appends a .exe to its filename

clean_files_Selfextract.sh: Removes the process dumps and memory dumps within the each folder inside CAPE directory

cape_printer.py: Automatically parses all the files within a selected folder and extracts the results inside 3 folders: Successfull samples, failed samples, and the successful samples' respective json output. 
