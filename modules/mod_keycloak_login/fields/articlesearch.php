<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Form\Field\TextField;

final class JFormFieldArticlesearch extends TextField
{
    protected $type = 'Articlesearch';

    protected function getInput()
    {
        $id = (string) ($this->id ?? '');
        $name = (string) ($this->name ?? '');
        $value = (int) ($this->value ?? 0);

        $db = Factory::getDbo();
        $title = '';
        if ($value > 0) {
            try {
                $query = $db->getQuery(true)
                    ->select($db->quoteName('title'))
                    ->from($db->quoteName('#__content'))
                    ->where($db->quoteName('id') . ' = ' . (int) $value);
                $db->setQuery($query);
                $title = (string) $db->loadResult();
            } catch (\Throwable $e) {
                $title = '';
            }
        }

        $html = '';
        $html .= '<input type="number" class="form-control" id="' . htmlspecialchars($id, ENT_QUOTES, 'UTF-8') . '" name="' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '" value="' . (int) $value . '" min="0" placeholder="Article ID">';
        
        if ($title !== '') {
            $titleEsc = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
            $html .= '<div class="form-text text-muted mt-1"><small>Current: <strong>' . $titleEsc . '</strong></small></div>';
        }

        return $html;
    }
}
