import random
import string
from .models import ChatRoom
from django.dispatch import receiver
from django.db.models.signals import pre_save
 
def random_string_generator(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


@receiver(pre_save, sender=ChatRoom)
def unique_room_key_generator(sender, instance, *args, **kwargs):
    room_key= random_string_generator()
    while ChatRoom.objects.filter(room_key=room_key).exists():
        room_key = random_string_generator()
    instance.room_key = room_key