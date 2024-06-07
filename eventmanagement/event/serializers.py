from rest_framework import serializers
from event.models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role','password']
        extra_kwargs = {'password': {'write_only': True}}
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
class EventSerializer(serializers.ModelSerializer):
    organizer_username = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = ['id', 'name', 'description', 'date', 'organizer', 'organizer_username']

    def get_organizer_username(self, obj):
        return obj.organizer.username
    

class RegistrationSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Registration
        fields = ['id', 'event', 'user', 'registered_at']
    

