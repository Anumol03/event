# signals.py

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Event
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

@receiver(post_save, sender=Event)
def notify_users(sender, instance, created, **kwargs):
    if created:
        message = f"New event created: {instance.name}"
    else:
        message = f"Event updated: {instance.name}"
    
    channel_layer = get_channel_layer()
    
    async_to_sync(channel_layer.group_send)(
        'notifications',
        {
            'type': 'send_notification',
            'message': message
        }
    )
