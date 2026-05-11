from django.db import models


class IOCRecord(models.Model):
    CONFIDENCE_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
    ]

    indicator = models.TextField()
    submitted_type = models.CharField(max_length=50)
    detected_type = models.CharField(max_length=50)
    source = models.CharField(max_length=255)
    date_found = models.CharField(max_length=50)
    is_valid = models.BooleanField(default=False)
    validation_notes = models.TextField()
    reputation = models.CharField(max_length=50, default="Unknown")
    reputation_notes = models.TextField()
    asn = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=255, blank=True)
    malware_family = models.CharField(max_length=255, blank=True)
    mitre_tactic = models.CharField(max_length=255, blank=True)
    mitre_technique = models.CharField(max_length=255, blank=True)
    mitre_notes = models.TextField(blank=True)
    confidence_level = models.CharField(max_length=10, choices=CONFIDENCE_CHOICES, default="Low")
    confidence_reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "id"]

    def __str__(self):
        return f"{self.indicator} ({self.detected_type})"
