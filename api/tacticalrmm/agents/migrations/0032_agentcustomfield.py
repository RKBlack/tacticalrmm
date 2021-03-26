# Generated by Django 3.1.7 on 2021-03-17 14:45

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0014_customfield'),
        ('agents', '0031_agent_alert_template'),
    ]

    operations = [
        migrations.CreateModel(
            name='AgentCustomField',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.TextField(blank=True, null=True)),
                ('agent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='custom_fields', to='agents.agent')),
                ('field', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='agent_fields', to='core.customfield')),
            ],
        ),
    ]
