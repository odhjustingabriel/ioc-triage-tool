from django import forms

MAX_CSV_FILES = 5
MAX_CSV_FILE_SIZE = 3 * 1024 * 1024
REQUIRED_CSV_COLUMNS = "indicator, type, source, date_found"


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, (list, tuple)):
            return [single_file_clean(file_data, initial) for file_data in data]
        return [single_file_clean(data, initial)]


class CSVUploadForm(forms.Form):
    csv_files = MultipleFileField(
        label="CSV files",
        help_text=(
            f"Select up to {MAX_CSV_FILES} CSV files. Each file must be {MAX_CSV_FILE_SIZE // (1024 * 1024)} MB "
            f"or smaller and include these columns: {REQUIRED_CSV_COLUMNS}."
        ),
        widget=MultipleFileInput(
            attrs={
                "accept": ".csv,text/csv",
                "class": "visually-hidden",
                "id": "id_csv_files",
            }
        ),
    )

    def clean_csv_files(self):
        uploaded_files = self.cleaned_data["csv_files"]
        if not uploaded_files:
            raise forms.ValidationError("Select at least one CSV file to triage.")
        if len(uploaded_files) > MAX_CSV_FILES:
            raise forms.ValidationError(f"Select no more than {MAX_CSV_FILES} CSV files at a time.")

        for uploaded_file in uploaded_files:
            if not uploaded_file.name.lower().endswith(".csv"):
                raise forms.ValidationError("Only CSV files are accepted. Please select another file.")
            if uploaded_file.size > MAX_CSV_FILE_SIZE:
                raise forms.ValidationError(
                    f"{uploaded_file.name} is larger than {MAX_CSV_FILE_SIZE // (1024 * 1024)} MB. "
                    "Please select another file."
                )
        return uploaded_files
