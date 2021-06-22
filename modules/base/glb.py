#!/bin/python3
# -*- coding: utf-8 -*-

'''Initiate the KRIS' global variables.'''

glb__auth = 'Lasercata'
glb__last_update = '22.06.2021'
glb__version = '1.1_kris'

##-import
from os import getcwd
from os.path import expanduser, isdir


##-main
#---------Path vars
KRIS_running_path = getcwd() #Cracker_running_path
KRIS_data_path = KRIS_running_path + '/Data' #Cracker_data_path


# #------Interface
# with open('{}/interface'.format(Cracker_data_path)) as f:
#     interface = f.read()

#------Home mode
if isdir(expanduser('~/.RSA_keys')):
    home = True

else:
    home = False
