from django.contrib import admin

from .models import IOCRecord


@admin.register(IOCRecord)
class IOCRecordAdmin(admin.ModelAdmin):
    list_display = ("indicator", "detected_type", "reputation", "confidence_level", "created_at")
    list_filter = ("detected_type", "reputation", "confidence_level", "is_valid")
    search_fields = ("indicator", "source", "mitre_tactic", "mitre_technique")
