library(
    identifier: 'jenkins-lib-common@v2.11.2',
    retriever: modernSCM([
        $class: 'GitSCMSource',
        remote: 'git@github.com:zextras/jenkins-lib-common.git',
        credentialsId: 'jenkins-integration-with-github-account'
    ])
)

properties(defaultPipelineProperties())

pipeline {
    options {
        buildDiscarder(logRotator(numToKeepStr: '5'))
        disableConcurrentBuilds()
        skipDefaultCheckout()
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
                gitMetadata()
            }
        }
        stage('Skip CI') {
            steps {
                script { semanticRelease.guard() }
            }
        }
        stage('SonarQube analysis') {
            steps {
                script {
                    scannerHome = tool 'SonarScanner';
                }
                withSonarQubeEnv(credentialsId: 'sonarqube-user-token',
                    installationName: 'SonarQube instance') {
                    sh "${scannerHome}/bin/sonar-scanner"
                }
            }
        }
        stage('Semantic Release') {
            steps {
                semanticRelease()
            }
        }
    }
}
