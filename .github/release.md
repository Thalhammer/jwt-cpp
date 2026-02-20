# Steps to perform a Release

1. Update version number in
    - CMakeLists.txt `write_basic_package_version_file()`
    - nuget/jwt-cpp.nuspec `<version>` and `<releaseNotes>`
    - Doxygen `PROJECT_NUMBER`
    - .github/ISSUE_TEMPLATE/bug-report.yml `id: version`
2. Draft new release on GitHub
    - Releases > Draft a new Release
    - Create a tag `vX.Y.Z` at `master`
        - add suffix `-rc.X` for testing release process
    - Review changes for any **Breaking Changes**
    - Add section `## Breaking Changes :warning:` if needed
        - separate corresponding Pull Requests
    - Publish Release
