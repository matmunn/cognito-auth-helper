const { createHmac } = require('crypto')

const { CognitoIdentityProvider } = require("@aws-sdk/client-cognito-identity-provider")

const commandLineArgs = require('command-line-args');
const getUsage = require('command-line-usage');
const PasswordPrompt = require('prompt-password');
const Enquirer = require('enquirer');

global['navigator'] = {
  userAgent: 'iOS'
};

function main() {
  const optionsDefinitions = [
    {
      name: 'user-pool-id',
      type: String,
      defaultValue: process.env.AWS_COGNITO_USER_POOL_ID,
      description: 'Cognito user pool ID ([bold]{required})'
    },

    {
      name: 'client-id',
      type: String,
      defaultValue: process.env.AWS_COGNITO_CLIENT_ID,
      description: 'Cognito client ID ([bold]{required})'
    },

    {
      name: 'client-secret',
      type: String,
      defaultValue: process.env.AWS_COGNITO_CLIENT_SECRET,
      description: 'Cognito client secret'
    },

    {
      name: 'region',
      type: String,
      defaultValue: process.env.AWS_REGION,
      description: 'AWS region ID ([bold]{required})'
    },

    {
      name: 'help',
      type: Boolean
    }
  ];

  const args = commandLineArgs(optionsDefinitions);

  if (args.help || !args['user-pool-id'] || !args['client-id']) {
    const sections = [
      {
        header: 'cognito-helper',
        content: 'Authenticates against your AWS Cognito user pool and returns an access token.'
      },

      {
        header: 'Options',
        optionList: optionsDefinitions
      }
    ];

    const usage = getUsage(sections);

    console.log(usage);
    return;
  }

  const poolData = {
    UserPoolId: args['user-pool-id'],
    ClientId: args['client-id'],
    ClientSecret: args['client-secret']
  };

  const enquirer = new Enquirer();

  enquirer.register('password', PasswordPrompt);

  const loginQuestions = [
    {
      name: 'username',
      message: 'Username:'
    },
    {
      name: 'password',
      message: 'Password:',
      type: 'password'
    }
  ];

  enquirer.ask(loginQuestions).then(({ username, password }) => {
    const cognitoClient = new CognitoIdentityProvider({
      region: args['region'],
    })

    const authOpts = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: args['client-id'],
      AuthParameters: {
        'USERNAME': username,
        'PASSWORD': password,
      },
    }

    if (args['client-secret']) {
      authOpts.AuthParameters.SECRET_HASH = createHmac("sha256", args['client-secret']).update(username + args['client-id']).digest("base64")
    }

    async function runAuthentication() {
      const response = await cognitoClient.initiateAuth(authOpts)
  
      console.log(response.AuthenticationResult.IdToken)
    }

    runAuthentication()
  })
}

main();
