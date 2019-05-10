from django import template

register = template.Library()


@register.filter(name='basename')
def basename(value):
    return value.split('/').pop()