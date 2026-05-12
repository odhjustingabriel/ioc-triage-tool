from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render

from .forms import CSVUploadForm, REQUIRED_CSV_COLUMNS
from .models import IOCRecord
from .services.reporting import generate_markdown_report, generate_pdf_report
from .services.triage import parse_csv_upload


def home(request):
    if request.method == "POST":
        form = CSVUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                all_results = []
                uploaded_files = form.cleaned_data["csv_files"]
                for uploaded_file in uploaded_files:
                    all_results.extend(parse_csv_upload(uploaded_file))
                IOCRecord.objects.bulk_create([IOCRecord(**result.__dict__) for result in all_results])
                messages.success(
                    request,
                    f"Processed {len(all_results)} IOC record(s) from {len(uploaded_files)} CSV file(s).",
                )
                return redirect("results")
            except ValueError as exc:
                error_message = str(exc).strip() or (
                    f"Invalid CSV upload. Ensure the file contains valid IOC rows and includes required columns: {REQUIRED_CSV_COLUMNS}."
                )
                messages.error(request, f"{error_message} Please select another file.")
            except UnicodeDecodeError:
                messages.error(request, "CSV must be UTF-8 encoded text. Please select another file.")
        else:
            messages.error(request, "Upload failed. Select 1 to 5 CSV files, each 3 MB or smaller.")
    else:
        form = CSVUploadForm()
    return render(request, "home.html", {"form": form})


def results(request):
    records = IOCRecord.objects.all()
    detected_type = request.GET.get("detected_type", "").strip()
    confidence = request.GET.get("confidence", "").strip()
    if detected_type:
        records = records.filter(detected_type=detected_type)
    if confidence:
        records = records.filter(confidence_level=confidence)
    context = {
        "records": records,
        "selected_type": detected_type,
        "selected_confidence": confidence,
        "type_options": IOCRecord.objects.exclude(detected_type="").values_list("detected_type", flat=True).distinct().order_by("detected_type"),
        "confidence_options": ["Low", "Medium", "High"],
    }
    return render(request, "results.html", context)


def report(request):
    records = IOCRecord.objects.all().order_by("id")
    markdown = generate_markdown_report(records)
    if request.GET.get("download") == "markdown":
        response = HttpResponse(markdown, content_type="text/markdown; charset=utf-8")
        response["Content-Disposition"] = 'attachment; filename="ioc_triage_report.md"'
        return response
    if request.GET.get("download") == "pdf":
        pdf_bytes = generate_pdf_report(records)
        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        response["Content-Disposition"] = 'attachment; filename="ioc_triage_report.pdf"'
        return response
    return render(request, "report.html", {"markdown": markdown, "records": records})
