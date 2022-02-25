from ast import Global
from django.contrib import admin

from golem.models import GolemAttack

# Register your models here.
class GolemAdmin(admin.ModelAdmin):
    list_display = ('id_name','status','source','peer','history')
    search_fields = ['id_name']
    history_list_display = ["history"]

admin.site.register(GolemAttack, GolemAdmin)
