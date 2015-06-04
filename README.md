#Installation
Add the directory to your `$SPLUNK_HOME/etc/apps` directory and copy the files in `SAMPLE_FILES` to `samples`.

The app is configured to batch import the files, so it will delete them after importing on the first launch. If you do not copy the files over you will not have any data in the app unless you manually add the Honeynet Challenge 5 sanitized log files to Splunk with the correct sourcetypes.
