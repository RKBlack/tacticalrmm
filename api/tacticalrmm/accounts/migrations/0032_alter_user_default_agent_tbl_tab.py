# Generated by Django 4.2.1 on 2023-05-17 07:11

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0031_user_date_format"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="default_agent_tbl_tab",
            field=models.CharField(
                choices=[
                    ("server", "Servers"),
                    ("workstation", "Workstations"),
                    ("mixed", "Mixed"),
                ],
                default="mixed",
                max_length=50,
            ),
        ),
    ]
