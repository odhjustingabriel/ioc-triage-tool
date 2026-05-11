# Generated for portfolio project initial schema
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="IOCRecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("indicator", models.TextField()),
                ("submitted_type", models.CharField(max_length=50)),
                ("detected_type", models.CharField(max_length=50)),
                ("source", models.CharField(max_length=255)),
                ("date_found", models.CharField(max_length=50)),
                ("is_valid", models.BooleanField(default=False)),
                ("validation_notes", models.TextField()),
                ("reputation", models.CharField(default="Unknown", max_length=50)),
                ("reputation_notes", models.TextField()),
                ("asn", models.CharField(blank=True, max_length=255)),
                ("country", models.CharField(blank=True, max_length=255)),
                ("malware_family", models.CharField(blank=True, max_length=255)),
                ("mitre_tactic", models.CharField(blank=True, max_length=255)),
                ("mitre_technique", models.CharField(blank=True, max_length=255)),
                ("mitre_notes", models.TextField(blank=True)),
                ("confidence_level", models.CharField(choices=[("Low", "Low"), ("Medium", "Medium"), ("High", "High")], default="Low", max_length=10)),
                ("confidence_reason", models.TextField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["-created_at", "id"]},
        ),
    ]
