import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="communityid",
    version="1.1",
    author="Christian Kreibich",
    author_email="christian@corelight.com",
    description="Community ID flow hashing",
    license="BSD",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/corelight/pycommunityid",
    packages=['communityid'],
    scripts=[
        'scripts/community-id',
        'scripts/community-id-pcap',
        'scripts/community-id-tcpdump'],
    test_suite="tests.communityid_test",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
)
