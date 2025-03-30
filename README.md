# Web Analyzer & Vulnerability Scanner (Termux)

Ce script Python est un outil d'analyse web et de détection de vulnérabilités conçu pour être exécuté dans l'environnement Termux. Il automatise la collecte d'informations essentielles sur un site web cible et effectue des vérifications de sécurité de base.

## À propos de l'outil

Cet outil permet d'obtenir rapidement un aperçu de la configuration et de la sécurité d'un site web. Il récupère des informations telles que les adresses IP associées, les enregistrements DNS, les détails d'enregistrement du domaine (WHOIS) et les en-têtes de réponse du serveur.

De plus, il tente d'identifier les technologies web couramment utilisées sur le site cible (par exemple, les systèmes de gestion de contenu comme WordPress ou Joomla) et recherche les sous-domaines potentiels.

Pour évaluer la sécurité de base, l'outil effectue un scan des ports communs pour identifier ceux qui sont ouverts et recherche certaines vulnérabilités courantes. Ces vulnérabilités peuvent inclure la divulgation d'informations sensibles via les en-têtes du serveur, l'absence d'en-têtes de sécurité importants et des problèmes spécifiques aux plateformes comme WordPress.

La sortie de l'outil est formatée avec des couleurs pour faciliter la lecture des résultats dans le terminal. Il offre également la possibilité de sauvegarder l'ensemble des données collectées dans un fichier au format JSON pour une analyse ultérieure ou pour la génération de rapports.

## Utilisation

L'outil est conçu pour être exécuté directement dans Termux et prend en charge plusieurs options pour personnaliser l'analyse, notamment la spécification de la cible, la sauvegarde des résultats dans un fichier, l'ajustement du nombre de threads utilisés pour certaines tâches et la définition d'un délai d'attente pour les requêtes. Un mode verbeux est également disponible pour afficher plus de détails pendant l'exécution.

**Avertissement :** Cet outil est destiné à des fins de test et d'éducation uniquement. Utilisez-le de manière responsable et uniquement sur des cibles pour lesquelles vous avez une autorisation explicite. L'utilisation de cet outil sans autorisation peut être illégale.
