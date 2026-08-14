export const TOKEN_PARAMETER = "token";

export function readTokensFromFragment(hash) {
  return new URLSearchParams(hash.replace(/^#/, "")).getAll(TOKEN_PARAMETER);
}

export function buildTokenUrl(currentUrl, tokens) {
  const url = new URL(currentUrl);
  const fragmentParameters = new URLSearchParams(url.hash.slice(1));

  // Clean up the earlier query-string format if an old link is edited.
  url.searchParams.delete(TOKEN_PARAMETER);
  fragmentParameters.delete(TOKEN_PARAMETER);
  tokens.forEach((token) => fragmentParameters.append(TOKEN_PARAMETER, token));
  url.hash = fragmentParameters.toString();

  return url;
}
