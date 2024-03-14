pipeline {
    options {
        skipDefaultCheckout()
        buildDiscarder(logRotator(numToKeepStr: '5'))
        timeout(time: 1, unit: 'HOURS')
    }
    agent {
        node {
            label 'base-agent-v2'
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
