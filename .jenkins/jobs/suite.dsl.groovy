@GrabResolver('https://artifactory.tagged.com/artifactory/libs-release-local/')
@Grab('com.tagged.build:jenkins-dsl-common:0.1.18')

import com.tagged.build.common.*

def memcached_project = new Project(
    jobFactory,
    [
        githubOwner: 'jdi-tagged',
        githubProject: 'memcached',
        githubHost: 'github.com',
        hipchatRoom:'PetsDev',
        email: 'jirwin@tagged.com'
    ]
)
def memcached = memcached_project.downstreamJob {
    jdk 'default'
    label 'orc01'
    steps{
        shell '''
bash << _EOF_
./autogen.sh
./configure
make dist
rm -rf SOURCES SPECS BUILD BUILDROOT RPMS SRPMS
mkdir SOURCES
mv *tar.gz SOURCES
echo workspace "$WORKSPACE"
rpmbuild \\
           --define "_topdir $WORKSPACE" \\
           --define "release `date +%Y%m%d%H%M%S`" \\
           -ba memcached.spec
_EOF_'''
    }
    triggers {
        githubPush()
        scm('5 * * * *')
    }
    publishers {          // mailer(String recipients, String dontNotifyEveryUnstableBuildBoolean = false, String sendToIndividualsBoolean = false)
        mailer(memcached_project.notifyEmail, true, true)
        archiveArtifacts('RPMS/**/*.rpm')
    }
    hipchat(memcached_project.hipchatRoom, false)
}
