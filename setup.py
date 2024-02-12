from setuptools import setup, find_packages, find_namespace_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()
long_description = (here / 'README.md').read_text(encoding='utf-8')

setup(
    name='cyst-models-dojo-cryton',
    version='0.1.0',
    description='Collection of CYST models used for the ai-dojo project',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://gitlab.ics.muni.cz/cyst/cyst-models-dojo-cryton',
    author='Martin Drasar et al.',
    author_email='drasar@ics.muni.cz',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Topic :: Scientific/Engineering',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
        'Topic :: Security',
        'Typing :: Typed',

        # Pick your license as you wish
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate you support Python 3. These classifiers are *not*
        # checked by 'pip install'. See instead 'python_requires' below.
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent'
    ],
    packages=find_packages(
        exclude=['tests', 'scenarios']
    ) + find_namespace_packages(
        include=['cyst_models.*', 'cyst_services.*']
    ),
    python_requires='>=3.9, <4',
    install_requires=[
        'cyst-core',
        'netaddr',
        'importlib_metadata',  # TODO: remove and replace with importlib.metadata in 3.10
        'pyyaml',
        'requests'
    ],
    entry_points={
        'cyst.models': [
            'cryton=cyst_models.cryton.main:behavioral_model_description'
        ],
    }
)
