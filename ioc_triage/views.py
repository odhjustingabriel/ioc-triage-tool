from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render

from .forms import CSVUploadForm
from .models import IOCRecord
from .services.reporting import generate_markdown_report
from .services.triage import parse_csv_upload


def home(request):
    if request.method == "POST":
        form = CSVUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                triage_results = parse_csv_upload(form.cleaned_data["csv_file"])
                IOCRecord.objects.bulk_create([IOCRecord(**result.__dict__) for result in triage_results])
                messages.success(request, f"Processed {len(triage_results)} IOC record(s).")
                return redirect("results")
            except ValueError as exc:
                messages.error(request, str(exc))
            except UnicodeDecodeError:
                messages.error(request, "CSV must be UTF-8 encoded text.")
        else:
            messages.error(request, "Please correct the upload error and try again.")
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
        try:
            from .services.reporting import generate_pdf_report

            pdf_bytes = generate_pdf_report(records)
        except ImportError:
            messages.error(request, "PDF export requires ReportLab. Install requirements.txt and try again.")
            return redirect("report")
        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        response["Content-Disposition"] = 'attachment; filename="ioc_triage_report.pdf"'
        return response
    return render(request, "report.html", {"markdown": markdown, "records": records})
