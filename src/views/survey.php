<?php
/** Encrypted forms stay disabled until survey.js has successfully exercised browser encryption. */
$n = 0;
?>
<article class="survey">
  <?php if ($isOwner && $survey['status'] === 'draft'): ?>
  <p class="preview-note"><?= e(t('Dit is een voorbeeld. Alleen jij ziet deze pagina tot je de enquête publiceert.')) ?> <a href="/enquetes/<?= $survey['public_id'] ?>"><?= e(t('Terug naar bewerken')) ?></a></p>
  <?php endif ?>

  <header class="survey-head">
    <h1><?= e($survey['title']) ?></h1>
    <?php if ($survey['description'] !== ''): ?><p class="survey-intro"><?= nl2br(e($survey['description'])) ?></p><?php endif ?>
    <?php require __DIR__ . '/_survey-owner.php' ?>
  </header>

  <?php if ($errors): ?>
  <div class="notice notice-error" role="alert" tabindex="-1" data-error-summary>
    <?php if (isset($errors[0])): ?><p><?= e($errors[0]) ?></p>
    <?php else: ?><p><?= e(tn(count($errors), 'Nog niet verstuurd. Eén vraag heeft je aandacht nodig.', 'Nog niet verstuurd. {n} vragen hebben je aandacht nodig.')) ?></p><?php endif ?>
  </div>
  <?php endif ?>

  <?php if ($encrypted): ?>
  <div id="encryption-unavailable" class="notice notice-error" role="status">
    <h2><?= e(t('Eerst op slot, dan versturen')) ?></h2>
    <?php if ($publicKey === null): ?>
    <p><?= e(t('Deze enquête kan nog geen versleutelde antwoorden ontvangen. Vraag de maker om in te loggen en de versleuteling klaar te zetten.')) ?></p>
    <?php else: ?>
    <p><?= e(t('Deze enquête versleutelt je antwoorden op jouw apparaat, zodat alleen de maker ze kan openen. Zolang dat niet lukt, kun je de enquête niet invullen. We versturen je antwoorden niet onversleuteld.')) ?></p>
    <p><?= e(t('Zet JavaScript aan voor deze site of open de link in een recente versie van Firefox, Chrome, Edge of Safari. Gebruik je de browser in een andere app? Open de link dan in je gewone browser.')) ?></p>
    <noscript><p><?= e(t('JavaScript staat uit of is niet beschikbaar. Zet het aan en laad deze pagina opnieuw om de enquête veilig in te vullen.')) ?></p></noscript>
    <?php endif ?>
  </div>
  <?php endif ?>

  <form method="post" action="<?= e($action) ?>" novalidate<?= $encrypted ? ' data-encrypted="true" hidden' : '' ?>>
    <?php if ($encrypted): ?><fieldset class="survey-fields" data-encrypted-fields disabled><?php endif ?>
    <?php if ($unlock): ?><input type="hidden" name="k" value="<?= e($unlock) ?>"><?php endif ?>
    <ol class="survey-questions">
      <?php foreach ($questions as $q):
        $n++;
        $qid = $q['id'];
        $name = "q[$qid]";
        $fid = "q$qid";
        $val = $posted[$qid] ?? null;
        $err = $errors[$qid] ?? null;
        $o = $q['options'];
        $grouped = in_array($q['type'], ['single', 'multi', 'yesno', 'stars', 'scale'], true);
        $describe = trim(($q['help'] !== '' ? "$fid-help " : '') . ($err ? "$fid-err" : ''));
        $aria = ($describe ? ' aria-describedby="' . $describe . '"' : '') . ($err ? ' aria-invalid="true"' : '');
        $req = $q['required'] ? ' required' : '';
      ?>
      <li class="sq<?= $err ? ' sq-error' : '' ?>" id="vraag-<?= $n ?>">
        <?php if ($grouped): ?><fieldset<?= $describe ? ' aria-describedby="' . $describe . '"' : '' ?>><legend><?php else: ?><label class="sq-title" for="<?= $fid ?>"><?php endif ?>
          <span class="sq-n"><?= $n ?></span>
          <span class="sq-text"><?= e($q['title']) ?><?php if ($q['required']): ?> <span class="req"><?= e(t('verplicht')) ?></span><?php endif ?></span>
        <?php if ($grouped): ?></legend><?php else: ?></label><?php endif ?>

        <div class="sq-body">
          <?php if ($q['help'] !== ''): ?><p class="hint" id="<?= $fid ?>-help"><?= nl2br(e($q['help'])) ?></p><?php endif ?>
          <?php if ($q['image_id']): ?><img class="sq-image" src="/afbeelding/<?= e($q['image_id']) ?>" alt="" loading="lazy"><?php endif ?>

          <?php switch ($q['type']):
            case 'short': ?>
              <input id="<?= $fid ?>" name="<?= $name ?>" type="text" maxlength="500" value="<?= e(is_string($val) ? $val : '') ?>"<?= $req . $aria ?>>
            <?php break; case 'long': ?>
              <textarea id="<?= $fid ?>" name="<?= $name ?>" rows="4" maxlength="5000"<?= $req . $aria ?>><?= e(is_string($val) ? $val : '') ?></textarea>
            <?php break; case 'email': ?>
              <input id="<?= $fid ?>" name="<?= $name ?>" type="email" maxlength="190" autocomplete="email" value="<?= e(is_string($val) ? $val : '') ?>"<?= $req . $aria ?>>
            <?php break; case 'date': ?>
              <input id="<?= $fid ?>" class="input-date" name="<?= $name ?>" type="date" value="<?= e(is_string($val) ? $val : '') ?>"<?= $req . $aria ?>>
            <?php break; case 'dropdown': ?>
              <select id="<?= $fid ?>" name="<?= $name ?>"<?= $req . $aria ?>>
                <option value=""><?= e(t('Kies een antwoord')) ?></option>
                <?php foreach ($o['choices'] ?? [] as $i => $c): ?><option value="<?= $i ?>"<?= $val === (string)$i ? ' selected' : '' ?>><?= e($c) ?></option><?php endforeach ?>
              </select>
            <?php break; case 'single': ?>
              <?php foreach ($o['choices'] ?? [] as $i => $c): ?>
              <label class="pick"><input type="radio" name="<?= $name ?>" value="<?= $i ?>"<?= $val === (string)$i ? ' checked' : '' ?><?= $req ?>><span><?= e($c) ?></span></label>
              <?php endforeach ?>
            <?php break; case 'multi': ?>
              <?php foreach ($o['choices'] ?? [] as $i => $c): ?>
              <label class="pick"><input type="checkbox" name="<?= $name ?>[]" value="<?= $i ?>"<?= is_array($val) && in_array((string)$i, $val, true) ? ' checked' : '' ?>><span><?= e($c) ?></span></label>
              <?php endforeach ?>
            <?php break; case 'yesno': ?>
              <div class="pick-row">
                <label class="pick"><input type="radio" name="<?= $name ?>" value="ja"<?= $val === 'ja' ? ' checked' : '' ?><?= $req ?>><span><?= e(t('Ja')) ?></span></label>
                <label class="pick"><input type="radio" name="<?= $name ?>" value="nee"<?= $val === 'nee' ? ' checked' : '' ?><?= $req ?>><span><?= e(t('Nee')) ?></span></label>
              </div>
            <?php break; case 'stars': ?>
              <div class="stars">
                <?php for ($i = 1; $i <= 5; $i++): ?>
                <label><input type="radio" name="<?= $name ?>" value="<?= $i ?>"<?= $val === (string)$i ? ' checked' : '' ?><?= $req ?>><span class="sr"><?= e(tn($i, '{n} ster', '{n} sterren')) ?></span>
                  <svg viewBox="0 0 24 24" width="36" height="36" aria-hidden="true"><path d="M12 2.6l2.9 6 6.5.9-4.7 4.6 1.1 6.5L12 17.5l-5.8 3.1 1.1-6.5L2.6 9.5l6.5-.9z"/></svg></label>
                <?php endfor ?>
              </div>
            <?php break; case 'scale': ?>
              <div class="scale n-<?= (int)($o['max'] ?? 10) - (int)($o['min'] ?? 1) + 1 ?>">
                <?php for ($i = (int)($o['min'] ?? 1); $i <= (int)($o['max'] ?? 10); $i++): ?>
                <label><input type="radio" name="<?= $name ?>" value="<?= $i ?>"<?= $val === (string)$i ? ' checked' : '' ?><?= $req ?>><span><?= $i ?></span></label>
                <?php endfor ?>
              </div>
              <?php if (($o['minLabel'] ?? '') !== '' || ($o['maxLabel'] ?? '') !== ''): ?>
              <p class="scale-ends"><span><?= e($o['minLabel'] ?? '') ?></span><span><?= e($o['maxLabel'] ?? '') ?></span></p>
              <?php endif ?>
          <?php endswitch ?>

          <?php if ($err): ?><p class="error" id="<?= $fid ?>-err"><?= e($err) ?></p><?php endif ?>
        </div>
        <?php if ($grouped): ?></fieldset><?php endif ?>
      </li>
      <?php endforeach ?>
    </ol>

    <div class="hp" aria-hidden="true"><label for="f-website">Website</label><input id="f-website" name="website" type="text" tabindex="-1" autocomplete="off"></div>

    <div class="survey-send">
      <button class="btn btn-red btn-l" type="submit" data-sending="<?= e(t('Versturen…')) ?>"><?= e(t('Antwoorden versturen')) ?></button>
      <p class="hint"><?= e($encrypted
          ? t('Je antwoorden worden op dit apparaat versleuteld en alleen {name} kan ze openen. Na het versturen onthoudt deze browser met één cookie dat je hebt geantwoord. Geen tracking.', ['name' => $owner['display_name']])
          : t('Je antwoorden gaan naar {name}. Na het versturen onthoudt deze browser met één cookie dat je hebt geantwoord. Geen tracking.', ['name' => $owner['display_name']])) ?></p>
    </div>
    <?php if ($encrypted): ?></fieldset><?php endif ?>
  </form>
  <?php if ($encrypted && $publicKey !== null):
    // What survey.js needs to check and seal the answers in the browser (src/e2e.php describes the format).
    $sealQuestions = array_map(fn($q) => ['id' => $q['id'], 'type' => $q['type'], 'required' => $q['required'],
        'choices' => $q['options']['choices'] ?? [], 'min' => (int)($q['options']['min'] ?? 1), 'max' => (int)($q['options']['max'] ?? 10)], $questions); ?>
  <script type="application/json" id="seal"><?= json_block(['key' => $publicKey, 'survey' => (int)$survey['id'], 'questions' => $sealQuestions, 't' => js_texts([
      'Je hebt nog niets ingevuld.', 'Kies een geldige datum.', 'Vul een geldig e-mailadres in, zoals naam@voorbeeld.nl.', 'Deze vraag is verplicht.',
      'Nog niet verstuurd. Eén vraag heeft je aandacht nodig.', 'Nog niet verstuurd. {n} vragen hebben je aandacht nodig.',
      'Niet verstuurd: je browser kon je antwoorden niet versleutelen. Ze staan nog op deze pagina. Probeer opnieuw. Blijft dit gebeuren, gebruik dan een recente browser.',
  ])]) ?></script>
  <?php endif ?>

  <?php require __DIR__ . '/_made-with.php' ?>
</article>
