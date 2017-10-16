#!/usr/bin/env python

from setuptools import setup

setup(name='httpie-svb-auth',
      version='1.0.4',
      description='SVB API auth plugin for HTTPie.',
      author='Jim Brusstar',
      author_email='jim.brusstar@gmail.com',
      url='https://github.com/svb/httpie-svb-auth',
      download_url='https://github.com/svb/httpie-svb-auth',
      py_modules=['httpie_svb_auth'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Environment :: Plugins',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Topic :: Internet :: WWW/HTTP',
          'Topic :: Utilities'
      ],
      license='MIT',
      keywords=['httpie', 'svb'],
      zip_safe=True,
      install_requires=['httpie>=0.7.0'],
      entry_points={'httpie.plugins.auth.v1': [
          'httpie_svb_auth = httpie_svb_auth:SVBAuthPlugin'
      ]})
