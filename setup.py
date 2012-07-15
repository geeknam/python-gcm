from distutils.core import setup

setup(
    name='python-gcm',
    version='0.1.1',
    packages=['gcm',],
    license='MIT',
    author='Minh Nam Ngo',
    author_email='nam@namis.me',
    url='http://blog.namis.me/python-gcm/',
    description='Python client for Google Cloud Messaging for Android (GCM)',
    long_description=open('README.md').read(),
)