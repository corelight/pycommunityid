import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="communityid",
    version="1.0",
    author="Christian Kreibich",
    author_email="christian@corelightcom",
    description="Community ID flow hashing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/corelight/pycommunityid",
    packages=['communityid'],
    scripts=['scripts/community-id-pcap', 'scripts/community-id-tcpdump'],
    test_suite="tests.communityid_test",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
)
