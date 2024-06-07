from django.shortcuts import render

from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.contrib.auth import get_user_model
from .models import *
from .serializers import *
from rest_framework.generics import ListAPIView,RetrieveUpdateAPIView,DestroyAPIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated

class UserCreateView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'ok', 'message': 'User created successfully', 'data': serializer.data}, status=status.HTTP_201_CREATED)
        return Response({'status': 'error', 'data': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
class UserListView(ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        users_data = serializer.data
        message = "List of users retrieved successfully."
        return Response({'status': 'ok', 'message': message, 'data': users_data}, status=status.HTTP_200_OK)
    
class UserEditView(RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        user_id = kwargs.get('pk')
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response({'status': 'ok', 'message': f'User profile  updated successfully', 'data': serializer.data}, status=status.HTTP_200_OK)
    

class UserDeleteView(DestroyAPIView):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        user_id = kwargs.get('pk')
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({'status': 'ok', 'message': f'User profile  deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    

class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if username is None or password is None:
            return Response({'detail': 'Both username and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'role': user.role
            }, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        

class EventCreateView(APIView):
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        mutable_data = request.data.copy()  
        organizer_username = mutable_data.get('organizer')  

        try:
            organizer = User.objects.get(username=organizer_username)  
        except User.DoesNotExist:
            return Response({'error': 'Organizer with username  does not exist'.format(organizer_username)}, status=status.HTTP_400_BAD_REQUEST)

       
        mutable_data['organizer'] = organizer.id

        serializer = self.serializer_class(data=mutable_data)

        if serializer.is_valid():
            event = serializer.save()

            # Include the organizer's username in the response data
            response_data = serializer.data
            response_data['organizer'] = organizer_username

            return Response({'status':'ok','message':'event created successfully','data':response_data}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class EventListView(ListAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]
   

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        events_data = serializer.data
        event_count = Event.objects.count()

        message = "List of events retrieved successfully."
        return Response({'status': 'ok', 'message': message,'event_count':event_count, 'data': events_data}, status=status.HTTP_200_OK)
    
class EventEditView(APIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        mutable_data = request.data.copy()


        organizer_username = mutable_data.pop('organizer', None)
        if organizer_username:
            try:
                organizer = User.objects.get(username=organizer_username)
                mutable_data['organizer'] = organizer.id
            except User.DoesNotExist:
                return Response({'error': f'Organizer with username {organizer_username} does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(instance, data=mutable_data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        
        response_data = serializer.data
        response_data['organizer'] = organizer_username

        return Response({'status': 'ok', 'message': 'Event updated successfully', 'data': response_data}, status=status.HTTP_200_OK)
    


class EventEditView(RetrieveUpdateAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        mutable_data = request.data.copy()

        organizer_username = mutable_data.pop('organizer', None)
        
        if isinstance(organizer_username, list) and len(organizer_username) > 0:
            
            organizer_username = organizer_username[0]

        if organizer_username:
            try:
                organizer = User.objects.get(username=organizer_username)
                mutable_data['organizer'] = organizer.id
            except User.DoesNotExist:
                return Response({'error': f'Organizer with username {organizer_username} does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(instance, data=mutable_data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        response_data = serializer.data
        

        return Response({'status': 'ok', 'message': 'Event updated successfully', 'data': response_data}, status=status.HTTP_200_OK)



class EventDeleteView(DestroyAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({'status': 'ok', 'message': 'Event deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    

class RegistrationCreateView(APIView):
    serializer_class = RegistrationSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            registration = serializer.save()
            event_name = registration.event.name
            username = registration.user.username
            response_data = {
                'status': 'ok',
                'message': 'Registration created successfully',
                'event': event_name,
                'user': username
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class RegistrationListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        registrations = Registration.objects.all()
        registrations_with_names = []
        registration_count = Registration.objects.count()

        for registration in registrations:
            event_name = registration.event.name
            username = registration.user.username
            response_data = {
                'event': event_name,
                'user': username
            }
            registrations_with_names.append(response_data)

        message = "List of registrations retrieved successfully."
        return Response({'status': 'ok', 'message': message,'registration_count': registration_count, 'data': registrations_with_names}, status=status.HTTP_200_OK)
    

class RegistrationUpdateView(APIView):
    serializer_class = RegistrationSerializer
    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        registration = get_object_or_404(Registration, pk=pk)
        serializer = self.serializer_class(registration, data=request.data)
        if serializer.is_valid():
            serializer.save()
            event_name = serializer.instance.event.name
            username = serializer.instance.user.username
            response_data = {
                'status': 'ok',
                'message': 'Registration updated successfully',
                'event': event_name,
                'user': username
            }
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class RegistrationDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        registration = get_object_or_404(Registration, pk=pk)
        registration.delete()
        return Response({'status': 'ok', 'message': 'Registration deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

   