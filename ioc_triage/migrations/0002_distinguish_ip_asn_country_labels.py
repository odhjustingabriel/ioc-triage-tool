from django.db import migrations


def distinguish_ip_asn_country_labels(apps, schema_editor):
    IOCRecord = apps.get_model("ioc_triage", "IOCRecord")
    IOCRecord.objects.filter(
        detected_type="ip",
        asn="Internal/private address",
        country="Internal/private address",
    ).update(
        asn="Not applicable - private IP",
        country="Private/internal network",
    )
    IOCRecord.objects.filter(
        detected_type="ip",
        asn="Not applicable",
        country="Not applicable",
    ).update(
        asn="Reserved/non-routable address",
        country="Not geolocated",
    )
    IOCRecord.objects.filter(
        detected_type="ip",
        asn="Unknown - external lookup not configured",
        country="Unknown - external lookup not configured",
    ).update(
        asn="External ASN lookup not configured",
        country="External GeoIP lookup not configured",
    )


def restore_ip_asn_country_labels(apps, schema_editor):
    IOCRecord = apps.get_model("ioc_triage", "IOCRecord")
    IOCRecord.objects.filter(
        detected_type="ip",
        asn="Not applicable - private IP",
        country="Private/internal network",
    ).update(
        asn="Internal/private address",
        country="Internal/private address",
    )
    IOCRecord.objects.filter(
        detected_type="ip",
        asn="Reserved/non-routable address",
        country="Not geolocated",
    ).update(
        asn="Not applicable",
        country="Not applicable",
    )
    IOCRecord.objects.filter(
        detected_type="ip",
        asn="External ASN lookup not configured",
        country="External GeoIP lookup not configured",
    ).update(
        asn="Unknown - external lookup not configured",
        country="Unknown - external lookup not configured",
    )


class Migration(migrations.Migration):
    dependencies = [
        ("ioc_triage", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(distinguish_ip_asn_country_labels, restore_ip_asn_country_labels),
    ]
