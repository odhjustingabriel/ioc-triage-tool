from django import forms


class CSVUploadForm(forms.Form):
    csv_file = forms.FileField(
        label="CSV file",
        help_text="Upload a CSV with indicator,type,source,date_found columns. Maximum size: 2 MB.",
    )

    def clean_csv_file(self):
        uploaded_file = self.cleaned_data["csv_file"]
        if not uploaded_file.name.lower().endswith(".csv"):
            raise forms.ValidationError("Only .csv files are accepted.")
        if uploaded_file.size > 2 * 1024 * 1024:
            raise forms.ValidationError("CSV file is too large. Please upload a file under 2 MB.")
        return uploaded_file
