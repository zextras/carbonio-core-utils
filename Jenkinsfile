library(
    identifier: 'jenkins-lib-common@v2.8.5',
    retriever: modernSCM([
        $class: 'GitSCMSource',
        remote: 'git@github.com:zextras/jenkins-lib-common.git',
        credentialsId: 'jenkins-integration-with-github-account'
    ])
)

properties(defaultPipelineProperties())

pipeline {
    options {
        skipDefaultCheckout()
        buildDiscarder(logRotator(numToKeepStr: '5'))
        timeout(time: 1, unit: 'HOURS')
    }
    agent {
        node {
            label 'base'
        }
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                stash includes: '**', name: 'staging'
            }
        }
        stage('SonarQube analysis') {
            steps {
                unstash 'staging'
                script {
                    scannerHome = tool 'SonarScanner';
                }
                withSonarQubeEnv(credentialsId: 'sonarqube-user-token',
                    installationName: 'SonarQube instance') {
                    sh "${scannerHome}/bin/sonar-scanner"
                }
            }
        }
    }
}
