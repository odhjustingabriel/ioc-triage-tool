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

    @property
    def asn_display(self):
        if not self.asn:
            return "—"
        if self.detected_type == "ip":
            legacy_asn_labels = {
                "Internal/private address": "Not applicable - private IP",
                "Not applicable": "Reserved/non-routable address",
                "Unknown - external lookup not configured": "External ASN lookup not configured",
            }
            if self.asn in legacy_asn_labels:
                return legacy_asn_labels[self.asn]
            if self.asn == self.country:
                return "ASN not available for this IP"
        return self.asn

    @property
    def country_display(self):
        if not self.country:
            return "—"
        if self.detected_type == "ip":
            legacy_country_labels = {
                "Internal/private address": "Private/internal network",
                "Not applicable": "Not geolocated",
                "Unknown - external lookup not configured": "External GeoIP lookup not configured",
            }
            if self.country in legacy_country_labels:
                return legacy_country_labels[self.country]
            if self.asn == self.country:
                return "GeoIP not available for this IP"
        return self.country

    def __str__(self):
        return f"{self.indicator} ({self.detected_type})"
