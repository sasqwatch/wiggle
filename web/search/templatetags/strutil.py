from django import template

register = template.Library()


@register.filter(name='hexnum')
def hexnum(value):
    return hex(value)

@register.filter(name="segment_name")
def segment_name(value):
    # FIXME: segment name should use a custom analyzer
    # searching name __TEXT throws Exception
    return value.split('.').pop()