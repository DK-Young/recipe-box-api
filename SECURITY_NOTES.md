# Security baseline – anonymous access
Date: 2026-10-30

## Findings

1. Anonymous read of all recipes
   - Method: GET
   - Path: /recipes
   - Status: 200 OK
   - Outcome: Returned ALL recipes, including `"is_public": false` secret recipe (id: 3, "Secret family hot sauce").
   - Impact: Any anonymous user can read private recipe data.

2. Anonymous update of private recipe
   - Method: PATCH
   - Path: /recipes/3
   - Status: 200 OK
   - Outcome: Changed title of recipe id 3 to "Totally Not Secret Hot Sauce" while `is_public` is still false.
   - Impact: Any anonymous user can modify private recipe data.

3. Anonymous create of private recipe
   - Method: POST
   - Path: /recipes
   - Status: 201 CREATED
   - Outcome: Created new recipe id 4 with title "Evil Test Recipe", `is_public: false`.
   - Impact: Any anonymous user can add arbitrary (including private/malicious) recipe data.

4. Anonymous delete of recipe
   - Method: DELETE
   - Path: /recipes/4
   - Status: 204 NO CONTENT
   - Outcome: Recipe id 4 ("Evil Test Recipe") was removed; subsequent GET /recipes shows only ids 1–3.
   - Impact: Any anonymous user can delete recipe data.