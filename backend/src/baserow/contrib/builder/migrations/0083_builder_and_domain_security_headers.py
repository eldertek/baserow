from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("builder", "0082_builder_untrusted_content")]

    operations = [
        migrations.AddField(
            model_name="builder",
            name="security_headers",
            field=models.JSONField(
                default=dict,
                db_default={},
                help_text="Default HTTP security header overrides for published sites of this application.",
            ),
        ),
        migrations.AddField(
            model_name="domain",
            name="security_headers",
            field=models.JSONField(
                default=dict,
                db_default={},
                help_text="Optional HTTP security header overrides applied when serving this published domain.",
            ),
        ),
    ]
