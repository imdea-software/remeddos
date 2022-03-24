from ast import Global
from django.contrib import admin

from golem.models import GolemAttack

# Register your models here.
class GolemAdmin(admin.ModelAdmin):
    list_display = ('id_name','status','ip_src','ip_dest','received_at','history')
    search_fields = ['id_name']
    history_list_display = ["history"]
    actions = ['delete']

    def delete(self,request,queryset):
        queryset.delete()
    delete.short_description = 'Delete the attack from the DB.'

admin.site.register(GolemAttack, GolemAdmin)
