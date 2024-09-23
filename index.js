import jwt from 'jsonwebtoken';
import { GraphQLError } from 'graphql';

async function informationsToken(token) {
  try {
    if (token.startsWith('Bearer ')) {
      token = token.slice(7); // Supprime le préfixe "Bearer "
    }
    // Vérifie le token et lance une erreur si le token est invalide ou expiré
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded; // Retourne le payload décodé 
  } catch (err) {
    // Vérifie si l'erreur est liée à un token expiré
    if (err.name === 'TokenExpiredError') {
      console.error('Le token a expiré.');
      throw new GraphQLError('Votre session a expiré. Veuillez vous reconnecter.', {
        extensions: {
          code: 'UNAUTHENTICATED',
        },
      });
    }
    console.error('Erreur lors de la vérification du token:', err.message);
    throw new GraphQLError('Le token est invalide. Veuillez fournir un token valide.', {
      extensions: {
        code: 'INVALID_TOKEN',
      },
    });
  }
}

export default informationsToken;